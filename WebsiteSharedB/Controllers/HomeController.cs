﻿using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace WebsiteSharedB.Controllers
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
            ViewBag.Claims = ((ClaimsPrincipal)User).Claims;

            return View();
        }

        public ActionResult Signout()
        {
            Request.GetOwinContext().Authentication.SignOut();

            return Redirect("/");
        }

        [AllowAnonymous]
        public void OidcSignOut(string sid)
        {
            var cp = (ClaimsPrincipal)User;
            var sidClaim = cp.FindFirst("sid");
            if (sidClaim != null && sidClaim.Value == sid)
            {
                Request.GetOwinContext().Authentication.SignOut("Cookies");
            }
        }

        // Dummy action, for "force log in link/button/uri"
        [Authorize]
        public ActionResult OidcSignIn()
        {
            return RedirectToAction("Index");
        }
    }
}