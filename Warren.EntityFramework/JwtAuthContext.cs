using Warren.Domain;
using Warren.Domain.Auditing;
using Warren.Domain.Users;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using System.Linq.Expressions;

namespace Warren.EntityFramework
{
    public class JwtAuthContext : IdentityDbContext<User, IdentityRole<int>, int>
    {
        #region DBSets
        private DbSet<User> Users { get; set; }

        private DbSet<AuthorizationToken> AuthorizationTokens { get; set; }

        #endregion

        public JwtAuthContext(DbContextOptions options) : base(options)
        {
        }

        public override int SaveChanges()
        {
            BeforeSave();
            return base.SaveChanges();
        }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            HandleInterfacedEntitiesQueryFilters(modelBuilder);
        }

        private void BeforeSave()
        {
            var addedEntities = ChangeTracker.Entries<Entity>().Where(e => e.State == EntityState.Added).ToList();

            addedEntities.ForEach(e =>
            {
                e.Entity.CreatedDate = DateTime.Now;
                e.Entity.ModifiedDate = DateTime.Now;
            });

            var modifiedEntities = ChangeTracker.Entries<Entity>().Where(e => e.State == EntityState.Modified).ToList();

            modifiedEntities.ForEach(e =>
            {
                e.Entity.ModifiedDate = DateTime.Now;
            });

            SetSoftDeleteProperty();
        }

        private void HandleInterfacedEntitiesQueryFilters(ModelBuilder modelBuilder)
        {
            HandleSoftDeleteInterfacedEntitiesQueryFilter(modelBuilder);
        }

        #region Soft-delete Methods
        private void SetSoftDeleteProperty()
        {
            var deletedEntities = ChangeTracker.Entries<ISoftDelete>().Where(e => e.State == EntityState.Deleted).ToList();
            deletedEntities.ForEach(e =>
            {

                e.Property<DateTime>("DeletedOn").CurrentValue = DateTime.UtcNow;
                e.Property<bool>(nameof(ISoftDelete.IsDeleted)).CurrentValue = true;
                e.State = EntityState.Modified;
            });
        }

        private void HandleSoftDeleteInterfacedEntitiesQueryFilter(ModelBuilder modelBuilder)
        {
            modelBuilder.Model.GetEntityTypes()
                .Where(p => typeof(ISoftDelete).IsAssignableFrom(p.ClrType))
                .ToList()
                .ForEach(entityType =>
                {
                    modelBuilder.Entity(entityType.ClrType)
                    .HasQueryFilter(ConvertFilterExpression<ISoftDelete>(e => !e.IsDeleted.HasValue || !e.IsDeleted.Value, entityType.ClrType));
                });
        }
        #endregion Soft-delete Methods

        #region Helpers
        private LambdaExpression ConvertFilterExpression<TInterface>(Expression<Func<TInterface, bool>> filterExpression, Type entityType)
        {
            var newParam = Expression.Parameter(entityType);
            var newBody = ReplacingExpressionVisitor.Replace(filterExpression.Parameters.Single(), newParam, filterExpression.Body);

            return Expression.Lambda(newBody, newParam);
        }
        #endregion Helpers
    }
}
