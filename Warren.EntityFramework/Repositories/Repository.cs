using Warren.Core.Repositories;
using Warren.Domain;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

namespace Warren.EntityFramework.Repositories
{
    public class Repository<T> : IRepository<T> where T : Entity
    {
        protected JwtAuthContext _context;
        protected DbSet<T> _entities;

        public Repository(JwtAuthContext context)
        {
            this._context = context;
            this._entities = context.Set<T>();
        }

        public void Delete(T entity)
        {
            if (entity == null)
                throw new ArgumentNullException("Entity null, cannot delete");
            _entities.Remove(entity);
            Save();
        }

        public T Get(int id)
        {
            if (id == 0)
                throw new ArgumentNullException("ID was null, failed to fetch entity");
            return _entities.FirstOrDefault(x => x.Id == id);
        }

        public T Get(int id, params Expression<Func<T, object>>[] includes)
        {
            if (id == 0)
                throw new ArgumentNullException("ID was null, failed to fetch entity");
            IQueryable<T> query = _entities;
            foreach (Expression<Func<T, object>> include in includes)
            {
                query = query.Include(include)
                    .Where(x => x.Id == id);
            }
            return query.FirstOrDefault();
        }

        public IQueryable<T> GetAll(params Expression<Func<T, object>>[] includes)
        {
            IQueryable<T> query = _entities;
            foreach (Expression<Func<T, object>> include in includes)
            {
                query = query.Include(include);
            }
            return query;
        }

        public IQueryable<T> FindBy(Expression<Func<T, bool>> predicate)
        {
            return this._entities.Where(predicate);
        }

        public IQueryable<T> FindBy(Expression<Func<T, bool>> predicate, params Expression<Func<T, object>>[] includes)
        {
            var query = this.FindBy(predicate);

            foreach (Expression<Func<T, object>> include in includes)
            {
                query = query.Include(include);
            }
            return query;
        }

        public IQueryable<T> GetAll()
        {
            return _entities.AsQueryable();
        }

        public void Insert(T entity)
        {
            if (entity == null)
            {
                throw new ArgumentNullException("Entity is null, cannot insert");
            }
            _entities.Add(entity);
            _context.SaveChanges();
        }
        
        public async Task<T> InsertAsync(T entity)
        {
            if (entity == null)
            {
                throw new ArgumentNullException("Entity is null, cannot insert");
            }
            await _entities.AddAsync(entity);
            _context.SaveChanges();

            return entity;
        }

        public void Insert(List<T> entities)
        {
            if (entities == null)
                throw new ArgumentNullException("Entities is null, cannot insert");
            foreach (var entity in entities)
            {
                _entities.Add(entity);
            }
            Save();
        }

        public T InsertAndGet(T entity)
        {
            if (entity == null)
                throw new ArgumentNullException("Entity is null, cannot insert");
            _entities.Add(entity);
            Save();
            return entity;
        }

        public int InsertAndGetId(T entity)
        {
            if (entity == null)
                throw new ArgumentNullException("Entity is null, cannot insert");
            _entities.Add(entity);
            Save();
            return entity.Id;
        }

        public void Save()
        {
            _context.SaveChanges();
        }

        public T Update(T entity)
        {
            if (entity == null)
                throw new ArgumentNullException("Entity is null, cannot update");
            _entities.Update(entity);
            Save();
            return entity;
        }
    }
}
