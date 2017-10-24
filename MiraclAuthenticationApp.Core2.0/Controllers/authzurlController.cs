using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;

namespace MiraclAuthenticationApp.Controllers
{
    public class authzurlController : Controller
    {
        [HttpPost]
        public async Task<IActionResult> Index()
        {
            var hostUrl = Request.Scheme + "://" + Request.Host.Value; 
            return Json(new { authorizeURL = await HomeController.GetUrl(hostUrl)});
        }
    }
}