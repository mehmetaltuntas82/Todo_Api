using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Todo_Api.Data;
using Todo_Api.DTOs;
using Todo_Api.Models;


namespace TodoApi.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/[controller]")]
    public class TodoController : ControllerBase
    {
        private readonly AppDbContext _context;

        public TodoController(AppDbContext context)
        {
            _context = context;
        }

        private int? GetUserId()
        {
            var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
            if (userIdClaim == null) return null;
            return int.Parse(userIdClaim.Value);
        }

        [HttpGet]
        public async Task<IActionResult> GetTodos()
        {
            var userId = GetUserId();
            if (userId == null) return Unauthorized();

            var todos = await _context.TodoItems
                .Where(t => t.UserId == userId)
                .ToListAsync();

            return Ok(todos);
        }

        [HttpPost]
        public async Task<IActionResult> CreateTodo(TodoItemDto dto)
        {
            var userId = GetUserId();
            if (userId == null) return Unauthorized();

            var todo = new TodoItem
            {
                Title = dto.Title,
                Description = dto.Description,
                IsCompleted = dto.IsCompleted,
                UserId = userId.Value,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _context.TodoItems.Add(todo);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetTodos), new { id = todo.Id }, todo);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateTodo(int id, TodoItemDto dto)
        {
            var userId = GetUserId();
            if (userId == null) return Unauthorized();

            var todo = await _context.TodoItems.FindAsync(id);
            if (todo == null || todo.UserId != userId.Value)
                return NotFound("Görev bulunamadı.");

            todo.Title = dto.Title;
            todo.Description = dto.Description;
            todo.IsCompleted = dto.IsCompleted;
            todo.UpdatedAt = DateTime.UtcNow;

            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteTodo(int id)
        {
            var userId = GetUserId();
            if (userId == null) return Unauthorized();

            var todo = await _context.TodoItems.FindAsync(id);
            if (todo == null)
                return NotFound("Görev bulunamadı.");

            if (todo.UserId != userId.Value)
                return Forbid("Başkasının todo'su silinmez");

            _context.TodoItems.Remove(todo);
            await _context.SaveChangesAsync();

            return NoContent();
        }
    }
}
