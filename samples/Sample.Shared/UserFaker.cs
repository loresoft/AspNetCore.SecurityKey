namespace Sample.Shared;

public class UserFaker : Faker<User>
{
    public UserFaker()
    {
        CustomInstantiator(f => new User(
                First: f.Name.FirstName(),
                Last: f.Name.LastName(),
                Email: f.Internet.Email()
            )
        );
    }

    private static readonly Lazy<UserFaker> _instance = new();

    public static UserFaker Instance => _instance.Value;
}
