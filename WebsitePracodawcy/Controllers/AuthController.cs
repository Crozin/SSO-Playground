using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using IdentityModel;
using Microsoft.Owin.Security.Cookies;

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
            Response.Cookies.Add(new HttpCookie("usic", "xx") { Expires = DateTime.UtcNow.AddDays(-1) });

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

        [AllowAnonymous]
        public ActionResult UniversalOidcSignIn(string token)
        {
            // TODO http referer check? POST only?

            Response.Cookies.Set(new HttpCookie("usic", token)
            {
                HttpOnly = true
            });

            // http://probablyprogramming.com/2009/03/15/the-tiniest-gif-ever
            return new FileContentResult(Convert.FromBase64String("R0lGODlhAQABAIABAP///wAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="), "image/gif");
        }

        [ChildActionOnly]
        public PartialViewResult SpreadUniversalOidcSignIn()
        {
            var links = Session["universal_signin"] ?? new List<string>();
            Session.Remove("universal_signin");

            return PartialView(links);
        }
    }
}