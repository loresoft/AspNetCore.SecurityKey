namespace Sample.Shared;

public class AddressFaker : Faker<Address>
{
    public AddressFaker()
    {
        CustomInstantiator(f => new Address(
                Line1: f.Address.StreetAddress(),
                Line2: f.Address.SecondaryAddress(),
                City: f.Address.City(),
                State: f.Address.State(),
                ZipCode: f.Address.ZipCode()
            )
        );
    }

    private static readonly Lazy<AddressFaker> _instance = new();

    public static AddressFaker Instance => _instance.Value;
}
