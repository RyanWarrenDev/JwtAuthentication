using Warren.Domain;
using System.Linq.Expressions;

namespace Warren.Core.Repositories
{
    public interface IRepository<T> where T : Entity
    {
        IQueryable<T> GetAll(params Expression<Func<T, object>>[] includes);

        IQueryable<T> GetAll();

        T Get(int id);

        T Get(int id, params Expression<Func<T, object>>[] includes);

        IQueryable<T> FindBy(Expression<Func<T, bool>> predicate);

        IQueryable<T> FindBy(Expression<Func<T, bool>> predicate, params Expression<Func<T, object>>[] includes);

        void Insert(T entity);
        
        Task<T> InsertAsync(T entity);

        void Insert(List<T> entities);

        int InsertAndGetId(T entity);

        T InsertAndGet(T entity);

        T Update(T entity);

        void Delete(T entity);

        void Save();
    }
}
