
using iText.Kernel.Font;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509;
using System;
using System.Collections.ObjectModel;
using System.ComponentModel.Design;
using System.Net;
using System.Net.Http;
using System.Reflection.PortableExecutable;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks.Dataflow;
using static Org.BouncyCastle.Math.EC.ECCurve;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SigningApp
{
    public class SignClass
    {
        public static string baseURL = "https://emea.api.dss.globalsign.com:8443/v2";

        private static string fieldName = "signature";

        private static string RESOURCE_FOLDER = "your resource folder";

        private static string SRC = RESOURCE_FOLDER + "contract.pdf";

        private static string DEST = RESOURCE_FOLDER + "Sign.pdf";

        private static string CONT = RESOURCE_FOLDER + "Container.pdf";

        private static string LTV = RESOURCE_FOLDER + "LTV.pdf";

        private static string Password = "your password";
        private static string Certificate = "your certificate";

        public static HttpClient client;
        public static string accessCode;


        public static void Main(string[] args) 
        {
            string reason = "";
            string location = "";
            bool shouldsign = false;
            while (true)
            {
                //add here your manner to retrieve the reason and location and the condition for which to do the signing
                if (shouldsign)
                {
                    SignPdf(reason, location);
                }
                shouldsign = false;
                //wait 5 seconds
                Thread.Sleep(5000);
                
            }
        }
        /// <summary>
        /// sign a pdf
        /// </summary>
        /// <param name="reden"></param>
        /// <param name="locatie"></param>
        /// <exception cref="Exception"></exception>
        public static void SignPdf(string reden, string locatie)
        {
            for (int i = 0; i < 5; i++)
            {
                PdfReader? tempreader = null;
                try
                {
                    if (client == null)
                    {
                        var handler = new HttpClientHandler();
                        handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                        handler.SslProtocols = SslProtocols.Tls12;
                        handler.ClientCertificates.Add(new X509Certificate2(Certificate, Password));
                        client = new HttpClient(handler);
                    }
                    //login if necessary
                    JObject identity = Identity();
                    if (identity == null)
                    {
                        throw new Exception("no identity");
                    }
                    string cert = (string)identity.GetValue("signing_cert");
                    string id = (string)identity.GetValue("id");
                    string oc1 = (string)identity.GetValue("ocsp_response");
                    JObject path = CertificatePath();
                    string ca = (string)path.GetValue("path");

                    //Create Certificate chain
                    X509Certificate[] chain = CreateChain(cert, ca);

                    //find the pdf
                    PdfReader reader = new PdfReader(SRC);



                    //create empty signature
                    PdfSigner stamper;
                    using (FileStream os = new FileStream(CONT, FileMode.OpenOrCreate))
                    {
                        stamper = new PdfSigner(reader, os, new StampingProperties());

                        PdfSignatureAppearance appearance = stamper.GetSignatureAppearance();
                        appearance.SetPageRect(new Rectangle(275, 590, 300, 200));
                        appearance.SetPageNumber(1);
                        appearance.SetLayer2FontSize(10f);
                        stamper.SetFieldName(fieldName);
                        appearance.SetCertificate(chain[0]);
                        appearance.SetReason(reden);
                        appearance.SetLocation(locatie);

                        IExternalSignatureContainer external = new ExternalBlankSignatureContainer(PdfName.Adobe_PPKLite,
                            PdfName.Adbe_pkcs7_detached);
                        try
                        {
                            stamper.SignExternalContainer(external, 8192);
                        }
                        catch (Exception)
                        {

                        }
                        //os.Dispose();
                    }

                    //OCSP (maak het geldig)
                    byte[] oc2 = Convert.FromBase64String(oc1);
                    OcspResp ocspResp = new OcspResp(oc2);

                    IExternalSignatureContainer gsContainer = new MyExternalSignatureContainer(id, chain, ocspResp);
                    tempreader = new PdfReader(CONT);
                    using (FileStream os1 = new FileStream(DEST, FileMode.OpenOrCreate))
                    {
                        PdfSigner signer = new PdfSigner(tempreader, os1, new StampingProperties());
                        PdfSigner.SignDeferred(signer.GetDocument(), fieldName, os1, gsContainer);
                    }
                    //close the reader so you can delete the CONT file
                    tempreader.Close();
                    //add long term validation
                    AddLTV(DEST, LTV, new OcspClientBouncyCastle(null),
                        new CrlClientOnline(), LtvVerification.Level.OCSP_CRL,
                        LtvVerification.Level.OCSP_CRL);
                    //delete the old files if they exist
                    if (File.Exists(DEST))
                    {
                        File.Delete(DEST);
                    }
                    if (File.Exists(CONT))
                    {
                        File.Delete(CONT);
                    }

                }
                catch
                (Exception e)
                {
                    //close the reader so you can delete the CONT file
                    if (tempreader != null)
                    {
                        tempreader.Close();
                    }
                    //in case the signing was corrupted best clean it all up
                    if (File.Exists(DEST))
                    {
                        File.Delete(DEST);
                    }
                    if (File.Exists(CONT))
                    {
                        File.Delete(CONT);
                    }
                    if (File.Exists(LTV))
                    {
                        File.Delete(LTV);
                    }
                }
            }
            throw new Exception("Signing failed 5 times");
        }

        /// <summary>
        /// login on globalsign
        /// </summary>
        public static void Login()
        {
            string Json;

            using (HttpRequestMessage request1 = new(new HttpMethod("POST"), baseURL + "/login"))
            {
                string body = "{\"api_key\": \"your key\",\"api_secret\": \"your secret\"}";
                request1.Content = new StringContent(body, Encoding.UTF8, "application/json");

                HttpResponseMessage response1 = client.SendAsync(request1).GetAwaiter().GetResult();
                Json = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                var temp = JObject.Parse(Json);
                accessCode = (string)temp.GetValue("access_token");
            }
        }
        /// <summary>
        /// retrieve an identity you might need to modify this if you sign a lot of files at once
        /// </summary>
        /// <returns></returns>
        public static JObject Identity()
        {
            string Json;
            //try twice
            for (int i = 1; i <= 2;)
            {
                using (HttpRequestMessage request1 = new(new HttpMethod("POST"), baseURL + "/identity"))
                {
                    request1.Headers.Add("Authorization", "Bearer " + accessCode);

                    string body = "{\"subject_dn\": {\"organizational_unit\": [\"your organizational unit\"]}}";
                    request1.Content = new StringContent(body, Encoding.UTF8, "application/json");

                    HttpResponseMessage response1 = client.SendAsync(request1).GetAwaiter().GetResult();
                    Json = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    if (response1.IsSuccessStatusCode)
                    {
                        return JObject.Parse(Json);
                    }
                    else
                    {
                        Login();
                    }
                }
            }
            return null;

        }
        /// <summary>
        /// get the cert path
        /// </summary>
        /// <returns></returns>
        public static JObject CertificatePath()
        {
            string Json;

            //try twice
            for (int i = 1; i <= 2;)
            {

                using (HttpRequestMessage request1 = new(new HttpMethod("GET"), baseURL + "/certificate_path"))
                {
                    request1.Headers.Add("Authorization", "Bearer " + accessCode);

                    HttpResponseMessage response1 = client.SendAsync(request1).GetAwaiter().GetResult();
                    Json = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    if (response1.IsSuccessStatusCode)
                    {
                        return JObject.Parse(Json);
                    }
                    else
                    {
                        Login();
                    }
                }
            }
            return null;
        }
        /// <summary>
        /// sign the container
        /// </summary>
        /// <param name="id"></param>
        /// <param name="digest"></param>
        /// <returns></returns>
        public static JObject SignCont( string id, string digest)
        {
            string Json;
            //try twice
            for (int i = 1; i <= 2;)
            {
                using (HttpRequestMessage request1 = new(new HttpMethod("GET"), baseURL + "/identity/" + id + "/sign/" + digest))
                {
                    request1.Headers.Add("Authorization", "Bearer " + accessCode);

                    HttpResponseMessage response1 = client.SendAsync(request1).GetAwaiter().GetResult();
                    Json = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (response1.IsSuccessStatusCode)
                    {
                        return JObject.Parse(Json);
                    }
                    else
                    {
                        Login();
                    }
                }
            }
        
            return null;
        }
        /// <summary>
        /// add a timestamp
        /// </summary>
        /// <param name="digest"></param>
        /// <returns></returns>
        public static JObject Timestamp(string digest)
        {
            string Json;
            for (int i = 1; i <= 2;)
            {
                using (HttpRequestMessage request1 = new(new HttpMethod("GET"), baseURL + "/timestamp/" + digest))
                {
                    request1.Headers.Add("Authorization", "Bearer " + accessCode);

                    HttpResponseMessage response1 = client.SendAsync(request1).GetAwaiter().GetResult();
                    Json = response1.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                    if (response1.IsSuccessStatusCode)
                    {
                        return JObject.Parse(Json);
                    }
                    else
                    {
                        Login();
                    }
                }
            }
            return null;
        }
        /// <summary>
        /// create the certificate chain
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="ca"></param>
        /// <returns></returns>
        public static X509Certificate[] CreateChain(string cert, string ca)
        {
            X509Certificate[] chainy = new X509Certificate[2];

            X509CertificateParser parser = new X509CertificateParser();

            chainy[0] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(cert)).CertificateStructure);
            chainy[1] = new X509Certificate(parser.ReadCertificate(Encoding.UTF8.GetBytes(ca)).CertificateStructure);

            return chainy;
        }
        /// <summary>
        /// add long term validation
        /// </summary>
        /// <param name="src"></param>
        /// <param name="dest"></param>
        /// <param name="ocsp"></param>
        /// <param name="crl"></param>
        /// <param name="timestampLevel"></param>
        /// <param name="signatureLevel"></param>
        static void AddLTV(string src, string dest, IOcspClient ocsp, ICrlClient crl,
            LtvVerification.Level timestampLevel, LtvVerification.Level signatureLevel)
        {
            //make closable or the files will stay open forever and throw errors when trying to delete
            FileStream stream = new FileStream(src, FileMode.Open);
            PdfReader reader = new PdfReader(stream);
            PdfDocument pdfDoc = new PdfDocument(reader, new PdfWriter(new FileStream(dest, FileMode.OpenOrCreate)), new StampingProperties().UseAppendMode());
            try
            {
                LtvVerification v = new LtvVerification(pdfDoc);
                SignatureUtil signatureUtil = new SignatureUtil(pdfDoc);

                IList<string> names = signatureUtil.GetSignatureNames();
                string sigName = names[(names.Count - 1)];

                PdfPKCS7 pkcs7 = signatureUtil.ReadSignatureData(sigName);

                if (pkcs7.IsTsp())
                {
                    v.AddVerification(sigName, ocsp, crl, LtvVerification.CertificateOption.WHOLE_CHAIN,
                        timestampLevel, LtvVerification.CertificateInclusion.YES);
                }
                else
                {
                    foreach (string name in names)
                    {
                        v.AddVerification(name, ocsp, crl, LtvVerification.CertificateOption.WHOLE_CHAIN,
                            signatureLevel, LtvVerification.CertificateInclusion.YES);
                    }
                }

                v.Merge();
                pdfDoc.Close();
                stream.Dispose();
                stream.Close();
                reader.Close();
            }
            catch (Exception)
            {
                stream.Dispose();
                stream.Close();
                reader.Close();
                pdfDoc.Close();
                //delete the erroring files
                if (File.Exists(dest))
                {
                    File.Delete(dest);
                }
                if (File.Exists(src))
                {
                    File.Delete(src);
                }
                throw;
            }
        }

        class MyExternalSignatureContainer : IExternalSignatureContainer
        {
            private string id;
            private X509Certificate[] chain;
            private OcspResp ocspResp;

            public MyExternalSignatureContainer(string id, X509Certificate[] chain, OcspResp ocspResp)
            {
                this.id = id;
                this.chain = chain;
                this.ocspResp = ocspResp;
            }

            public byte[] Sign(Stream data)
            {
                BasicOcspResp basicResp = (BasicOcspResp)ocspResp.GetResponseObject();
                byte[] oc = basicResp.GetEncoded();
                Collection<byte[]> ocspCollection = new()
                {
                    oc
                };
                string hashAlgorithm = "SHA256";
                PdfPKCS7 sgn = new(null, chain, hashAlgorithm, false);

                byte[] hash = DigestAlgorithms.Digest(data, DigestAlgorithms.GetMessageDigest(hashAlgorithm));

                byte[] sh = sgn.GetAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CADES, ocspCollection,
                    null);

                //create sha256 message digest
                sh = SHA256.HashData(sh);

                //create hex encoded sha256 message digest
                string hexencodedDigest = new BigInteger(1, sh).ToString(16).ToUpper();

                JObject signed = SignClass.SignCont(id, hexencodedDigest);
                string sig = (string)signed.GetValue("signature");

                //decode hex signature
                byte[] dsg = Hex.Decode(sig);

                //include signature on PDF
                sgn.SetExternalDigest(dsg, null, "RSA");

                //create TimeStamp Client
                ITSAClient tsc = new DSSTSAClient();

                return sgn.GetEncodedPKCS7(hash, PdfSigner.CryptoStandard.CADES, tsc, ocspCollection, null);
            }

            public void ModifySigningDictionary(PdfDictionary signDic)
            {
            }
        }

        class DSSTSAClient : ITSAClient
        {
            public static int DEFAULTTOKENSIZE = 4096;
            public static string DEFAULTHASHALGORITHM = "SHA-256";

            public DSSTSAClient()
            {
            }

            public IDigest GetMessageDigest()
            {
                return new Sha256Digest();
            }

            public byte[] GetTimeStampToken(byte[] imprint)
            {
                TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
                tsqGenerator.SetCertReq(true);

                BigInteger nonce = BigInteger.ValueOf((long)(new TimeSpan(DateTime.Now.Ticks)).TotalMilliseconds);

                TimeStampRequest request = tsqGenerator.Generate(new DerObjectIdentifier(
                        DigestAlgorithms.GetAllowedDigest(DEFAULTHASHALGORITHM)),
                    imprint, nonce);

                JObject time = Timestamp(Hex.ToHexString(request.GetMessageImprintDigest()));
                string tst = (string)time.GetValue("token");
                byte[] token = Base64.Decode(tst);

                CmsSignedData cms = new(token);

                TimeStampToken tstToken = new(cms);
                return tstToken.GetEncoded();
            }

            public int GetTokenSizeEstimate()
            {
                return DEFAULTTOKENSIZE;
            }
        }
    }
}
