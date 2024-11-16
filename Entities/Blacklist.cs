namespace WebApi.Entities;
public class Blacklist
{
    public int Id { get; set; }
    public string Email { get; set; } = null!;
    public DateTime DateAdded { get; set; }
    public string Comment { get; set; }
}