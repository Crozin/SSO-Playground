using System.Linq;
using System.Security.Claims;
using System.Web.Mvc;

namespace Website1.Controllers
{
    public class BuyController : Controller
    {
        [Authorize]
        public ActionResult Index()
        {
            var cs = (ClaimsPrincipal) User;

            if (cs.Claims.Any(c => c.Type == "amr" && c.Value == "2fa"))
            {

                return View("Index");
            }
            else
            {
                return View("Upgrade2Fa");
            }
        }
    }
}