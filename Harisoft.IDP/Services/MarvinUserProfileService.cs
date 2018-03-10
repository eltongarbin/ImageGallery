using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Harisoft.IDP.Services
{
    public class MarvinUserProfileService : IProfileService
    {
        public MarvinUserProfileService(IMarvinUserRepository marvinUserRepository) {
            MarvinUserRepository = marvinUserRepository;
        }

        public IMarvinUserRepository MarvinUserRepository { get; }

        public Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            var claimsForUser = MarvinUserRepository.GetUserClaimsBySubjectId(subjectId);

            context.IssuedClaims = claimsForUser.Select(claim => new Claim(claim.ClaimType, claim.ClaimValue)).ToList();
            return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            var subjectId = context.Subject.GetSubjectId();
            context.IsActive = MarvinUserRepository.IsUserActive(subjectId);

            return Task.CompletedTask;
        }
    }
}
