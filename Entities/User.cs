namespace WebApi.Entities;

using System.Text.Json.Serialization;
/// this is a user
public class User
{
    public long Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public Role Role { get; set; }

    [JsonIgnore]
    public string PasswordHash { get; set; }
    [JsonIgnore]
    public DateTime DateCreated { get; set; }
    [JsonIgnore]
    public DateTime DateLastModified { get; set; }
    [JsonIgnore]
    public DateTime DateLastPasswordModified { get; set; }
    [JsonIgnore]
    public bool IsActivated { get; set; }
}