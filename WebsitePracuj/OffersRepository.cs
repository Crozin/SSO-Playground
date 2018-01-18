using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using IdentityModel.Client;
using Newtonsoft.Json;

namespace WebsitePracuj
{
    public class OffersRepository
    {
        public class Offer
        {
            public string Title { get; set; }
        }

        public async Task<ICollection<Offer>> GetRecentAsync()
        {
            using (var dc = new DiscoveryClient("http://auth.sso.com") { Policy = { RequireHttps = false } })
            {
                var so = await dc.GetAsync();

                using (var tc = new TokenClient(so.TokenEndpoint, "websitepracuj", "secret"))
                using (var client = new HttpClient())
                {
                    var tr = await tc.RequestClientCredentialsAsync("api_offers");

                    if (tr.IsError)
                        throw new Exception(tr.Error);

                    client.BaseAddress = new Uri("http://internal-api-offers.sso/");
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tr.AccessToken);

                    using (var response = await client.GetAsync("recent"))
                    {
                        response.EnsureSuccessStatusCode();

                        var content = await response.Content.ReadAsStringAsync();

                        return JsonConvert.DeserializeObject<ICollection<Offer>>(content);
                    }
                }
            }
        }
    }
}