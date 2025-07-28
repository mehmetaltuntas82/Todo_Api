namespace Todo_Api.DTOs
{
    public class TodoItemDto
    {
        public string Title { get; set; }
        public string? Description { get; set; }
        public bool IsCompleted { get; set; } = false;
    }
}
