using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using IdentityModel;
using Microsoft.Owin.Security.Cookies;
using SharedNet;

namespace WebsitePracodawcy.Controllers
{
    public class AuthController : Controller
    {
        [Authorize]
        public ActionResult SignIn()
        {
            return Redirect("/");
        }

        [Authorize]
        public ActionResult SignOut()
        {
            Request.GetOwinContext().Authentication.SignOut();
            Response.Cookies.Set(new HttpCookie("usic", "x")
            {
                HttpOnly = true,
                Expires = DateTime.Now.Subtract(TimeSpan.FromDays(100))
            });

            return Redirect("/");
        }

        [AllowAnonymous]
        public void OidcSignOut(string sid)
        {
            var cp = (ClaimsPrincipal) User;
            var sidClaim = cp.FindFirst(JwtClaimTypes.SessionId);

            if (sidClaim != null && sidClaim.Value == sid)
            {
                if (Request.Cookies["usic"] != null)
                {
                    Response.Cookies.Add(new HttpCookie("usic") { Expires = DateTime.Now.AddDays(-1d) });
                }

                Request.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            }
        }

        [HttpPost, AllowAnonymous]
        public ActionResult UniversalOidcSignIn(string code)
        {
            Response.AddHeader("Access-Control-Allow-Origin", "*");
            Response.Cookies.Set(new HttpCookie("usic", code)
            {
                HttpOnly = true,
                Expires = DateTime.Now.AddDays(60)
            });

            // http://probablyprogramming.com/2009/03/15/the-tiniest-gif-ever
            return new FileContentResult(Convert.FromBase64String("R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="), "image/gif");
        }

        [ChildActionOnly]
        public PartialViewResult SpreadUniversalOidcSignIn()
        {
            var links = Session["universal_sign_in"] ?? new List<UniversalSignInCodeDto>();
            Session.Remove("universal_sign_in");

            return PartialView(links);
        }
    }
}