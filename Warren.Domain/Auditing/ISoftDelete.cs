

namespace Warren.Domain.Auditing
{
    public interface ISoftDelete
    {
        bool? IsDeleted { get; set; }
    }
}
