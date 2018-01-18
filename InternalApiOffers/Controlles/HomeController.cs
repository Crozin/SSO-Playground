using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace InternalApiOffers.Controlles
{
    public class HomeController : ApiController
    {
        public static ConcurrentDictionary<string, Offer> Database = new ConcurrentDictionary<string, Offer>
        {
            ["AXG"] = new Offer("AXG", "Programista PHP", DateTime.UtcNow),
            ["HTT"] = new Offer("HTT", "Programista .NET", DateTime.UtcNow),
            ["MGX"] = new Offer("MGX", "Administrator bazy danych", DateTime.UtcNow),
            ["ZZA"] = new Offer("ZZA", "Sprzedawca jabłek", DateTime.UtcNow),
            ["GT6"] = new Offer("GT6", "Sprzedawca gruszek", DateTime.UtcNow),
            ["Z1O"] = new Offer("Z1O", "Kierowca Ubera", DateTime.UtcNow),
            ["B99"] = new Offer("B99", "Kierowca Taxi", DateTime.UtcNow)
        };

        [HttpGet, Route("{id}"), ClaimsAuthorize(new[] { "api_offers:read" })]
        public Offer Recent(string id)
        {
            if (Database.TryGetValue(id.ToUpperInvariant(), out Offer offer))
            {
                return offer;
            }

            throw new HttpResponseException(Request.CreateResponse(HttpStatusCode.NotFound, "Uh, oh... ni ma :("));
        }

        [HttpGet, Route("search"), ClaimsAuthorize(new[] { "api_offers:read" })]
        public IList<Offer> Search(string query)
        {
            return Database.Values.Where(o => o.Title.ToLowerInvariant().Contains(query.ToLowerInvariant())).ToList();
        }

        [HttpGet, Route("recent"), ClaimsAuthorize(new[] { "api_offers:read" })]
        public IList<Offer> Recent()
        {
            return Database.Values.OrderByDescending(o => o.Created).Take(3).ToList();
        }

        [HttpPost, Route("publish"), ClaimsAuthorize(new[] { "api_offers:publish" })]
        public HttpResponseMessage Publish(Offer newOffer)
        {
            if (newOffer == null || !newOffer.IsValid())
                return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Coś jest nie tak z przesłaną ofertą (brak ID/TITLE bądź zły format ID)");

            newOffer.Created = DateTime.UtcNow;

            if (Database.TryAdd(newOffer.Id, newOffer))
            {
                return Request.CreateResponse(HttpStatusCode.OK, "OK");
            }

            return Request.CreateErrorResponse(HttpStatusCode.BadRequest, "Coś poszło nie tak (ID zduplikowane?)");
        }
    }

    public class Offer
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public DateTime Created { get; set; }

        public Offer(string id, string title, DateTime created)
        {
            Id = id;
            Title = title;
            Created = created;
        }

        internal bool IsValid()
        {
            if (Id == null || Title == null)
                return false;

            if (Id.Length != 3)
                return false;

            return Id.Equals(Id.ToUpperInvariant(), StringComparison.InvariantCulture);
        }
    }
}