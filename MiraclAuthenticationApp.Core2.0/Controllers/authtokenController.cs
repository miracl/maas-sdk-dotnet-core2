using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace MiraclAuthenticationApp.Controllers
{
    public class authtokenController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Index()
        {
            string data = new System.IO.StreamReader(Request.Body).ReadToEnd();
            JToken code, userId;
            try
            {
                var d = JObject.Parse(data);
                if (!d.TryGetValue("code", out code) || !d.TryGetValue("userID", out userId))
                {
                    return new StatusCodeResult(StatusCodes.Status400BadRequest); 
                }
            }
            catch
            {
                return new StatusCodeResult(StatusCodes.Status400BadRequest);
            }

            var authProperties = await HomeController.Client.ValidateAuthorizationCode(code.ToString(), userId.ToString());
            if (authProperties == null)
            {
                return new StatusCodeResult(StatusCodes.Status401Unauthorized);
            }
            
            var accessToken = authProperties.GetTokenValue(OpenIdConnectParameterNames.AccessToken);            
            if (accessToken == null)
            {
                return StatusCode(StatusCodes.Status400BadRequest);
            }

            return StatusCode(StatusCodes.Status200OK, Json(accessToken));            
        }
    }
}