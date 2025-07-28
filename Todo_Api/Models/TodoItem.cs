using System.ComponentModel.DataAnnotations;
using TodoApi.Models;

namespace Todo_Api.Models
{
    public class TodoItem : BaseEntity
    {
        [Required]
        public string Title { get; set; }

        public bool IsCompleted { get; set; }
        public string Description {  get; set; }
        public int UserId { get; set; }
    }
}
