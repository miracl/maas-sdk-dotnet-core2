using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Miracl;
using System.IO;

namespace demo.Controllers
{
    public class dvsController : Controller
    {
        [HttpPost]
        public async Task<JsonResult> VerifySignature()
        {
            string reqBody = new StreamReader(Request.Body).ReadToEnd();

            var data = JObject.Parse(reqBody);
            var sign =  data.TryGetValue("signature", out JToken value) ? value : null;

            var mPinId = sign.Value<string>("mpinId");
            var publicKey = sign.Value<string>("publicKey");
            var u = sign.Value<string>("u");
            var v = sign.Value<string>("v");
            var docHash = sign.Value<string>("hash");
            var timeStamp = data.Value<int?>("timestamp") ?? 0;

            var signature = new Signature(docHash, mPinId, u, v, publicKey);
            var verificationResult = await Startup.Client.DvsVerifySignatureAsync(signature, timeStamp);

            return Json(new { valid = verificationResult.IsSignatureValid, status = verificationResult.Status.ToString() });
        }

        [HttpPost]
        public JsonResult CreateDocumentHash()
        {
            string document = new StreamReader(Request.Body).ReadToEnd();

            var docHash = Startup.Client.DvsCreateDocumentHash(document);
            var timeStamp = (int)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

            var documentData = new { hash = docHash, timestamp = timeStamp };

            return Json(documentData);
        }
    }
}
