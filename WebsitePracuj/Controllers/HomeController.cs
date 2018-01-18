using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace WebsitePracuj.Controllers
{
    public class HomeController : Controller
    {
        public async Task<ActionResult> Index()
        {
            var or = new OffersRepository();
            var offers = await or.GetRecentAsync();

            return View(new HomeIndexViewModel(offers.Select(o => new HomeIndexViewModel.OfferViewModel(o.Title)).ToList().AsReadOnly()));
        }

        [Authorize]
        public ActionResult Protected()
        {
            var cp = (ClaimsPrincipal) User;

            ViewBag.Claims = cp.Claims;

            return View();
        }
    }

    public class HomeIndexViewModel
    {
        public class OfferViewModel
        {
            public string Title { get; }

            public OfferViewModel(string title)
            {
                Title = title;
            }
        }

        public IReadOnlyList<OfferViewModel> Offers { get; }

        public HomeIndexViewModel(IReadOnlyList<OfferViewModel> offers)
        {
            Offers = offers;
        }
    }
}