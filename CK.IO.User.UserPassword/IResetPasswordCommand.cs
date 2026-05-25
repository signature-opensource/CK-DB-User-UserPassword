using CK.Core;
using CK.Cris;

namespace CK.IO.User.UserPassword;

public interface IResetPasswordCommand : ICommand<SimpleUserMessage>, ICommandCurrentCulture
{
    public string Token { get; set; }
    public string Password { get; set; }
}
