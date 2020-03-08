using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using IdentityServer4.EntityFramework.DbContexts;
using JetBrains.Annotations;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DockerDemo.IdentityServer.Infrastructure
{
    /// <inheritdoc />
    [UsedImplicitly]
    public class InitializeDatabaseService : BackgroundService
    {
        private readonly ConfigurationDbContext _configurationDbContext;

        private readonly IdentityContext _identityContext;

        private readonly PersistedGrantDbContext _persistedGrantDbContext;


        public InitializeDatabaseService(IServiceScopeFactory serviceScopeFactory)
        {
            var sp = serviceScopeFactory.CreateScope().ServiceProvider;
            _configurationDbContext = sp.GetRequiredService<ConfigurationDbContext>();
            _persistedGrantDbContext = sp.GetRequiredService<PersistedGrantDbContext>();
            _identityContext = sp.GetRequiredService<IdentityContext>();
        }

        /// <inheritdoc />
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _persistedGrantDbContext.Database.Migrate();
            _identityContext.Database.Migrate();

            _configurationDbContext.Database.Migrate();
        }
    }
}