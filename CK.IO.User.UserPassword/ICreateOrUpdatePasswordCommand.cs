using CK.Auth;
using CK.Cris;
using CK.DB.Auth;
using System.ComponentModel;

namespace CK.IO.User.UserPassword;

public interface ICreateOrUpdatePasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthNormal
{
    public int UserId { get; set; }
    public string Password { get; set; }
    [DefaultValue( UCLMode.CreateOrUpdate )]
    public UCLMode UCLMode { get; set; }
}
