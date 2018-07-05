using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace demo.Controllers
{
    public class configController : Controller
    {
        public async Task<JsonResult> Index()
        {
            Startup.Client.ClearUserInfo(false);

            var url = "http://localhost:8000"; // this can't be arbitrary because the demo will be used for integration tests
            var authUrl = await Startup.Client.GetAuthorizationRequestUrlAsync(url);
            var redirectURL = url + Startup.Client.Options.CallbackPath;

            // dotnet core exchanges the UserState protected
            Uri l =  new Uri(authUrl);
            var query = QueryHelpers.ParseQuery(l.Query);
            var items = query.SelectMany(x => x.Value, (col, value) => new KeyValuePair<string, string>(col.Key, value)).ToList();

            var state = items.First(i => i.Key == "state").Value;
            var nonce = items.First(i => i.Key == "nonce").Value;

            var demoCfg = new
            {
                clientID = Startup.Client.Options.ClientId,
                redirectURL,
                state,
                nonce
            };

            return Json(demoCfg);
        }
    }
}