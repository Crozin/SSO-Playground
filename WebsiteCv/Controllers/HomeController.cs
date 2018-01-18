﻿using System.Security.Claims;
using System.Web.Mvc;

namespace WebsiteCv.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult Protected()
        {
            var cp = (ClaimsPrincipal) User;

            ViewBag.Claims = cp.Claims;

            return View();
        }
    }
}