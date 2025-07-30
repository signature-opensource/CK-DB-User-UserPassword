using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

public interface ISetPasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthNormal
{
    public int UserId { get; set; }
    public string Password { get; set; }
}
