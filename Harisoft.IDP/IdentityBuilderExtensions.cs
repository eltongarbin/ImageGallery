﻿using Harisoft.IDP.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Harisoft.IDP
{
    public static class IdentityBuilderExtensions
    {
        public static IIdentityServerBuilder AddMarvinUserStore(this IIdentityServerBuilder builder)
        {
            builder.Services.AddScoped<IMarvinUserRepository, MarvinUserRepository>();
            builder.AddProfileService<MarvinUserProfileService>();
            return builder;
        }
    }
}
