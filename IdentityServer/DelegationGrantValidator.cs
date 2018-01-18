using System.Linq;
using System.Threading.Tasks;
using IdentityServer3.Core.Services;
using IdentityServer3.Core.Validation;

namespace IdentityServer
{
    public class DelegationGrantValidator : ICustomGrantValidator
    {
        private readonly TokenValidator tokenValidator;

        public DelegationGrantValidator(TokenValidator tokenValidator)
        {
            this.tokenValidator = tokenValidator;
        }

        public async Task<CustomGrantValidationResult> ValidateAsync(ValidatedTokenRequest request)
        {
            var token = request.Raw.Get("token");

            if (string.IsNullOrEmpty(token))
            {
                return new CustomGrantValidationResult($"Missing '{nameof(token)}' parameter.");
            }

            var tvr = await tokenValidator.ValidateAccessTokenAsync(token);

            if (tvr.IsError)
            {
                return new CustomGrantValidationResult(tvr.Error);
            }

            var sub = tvr.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (string.IsNullOrEmpty(sub))
            {
                return new CustomGrantValidationResult($"Missing '{nameof(sub)}' claim in '{nameof(token)}'.");
            }

            return new CustomGrantValidationResult(sub, GrantType);
        }

        public string GrantType => "delegation";
    }
}