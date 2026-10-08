using CK.Auth;
using CK.Core;
using CK.Cris;
using CK.IO.Authentication;
using CK.IO.Authentication.Basic;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Tests;

/// <summary>
/// The <see cref="IBasicLoginCommand"/> handler: the authentication center opens the session with a BasicLoginPayload.
/// (The login of the payload by the provider is tested by <see cref="BasicLoginProviderTests"/>.)
/// </summary>
[TestFixture]
public class BasicLoginCommandTests
{
    sealed class RecordingOpener : IAuthenticationSessionOpener
    {
        public string? Scheme;
        public object? Payload;
        public bool RememberMe;

        public ValueTask<ISessionResult> OpenSessionAsync<T>( IActivityMonitor monitor, T command, string scheme, object payload, bool rememberMe = false )
            where T : ICommand<ISessionResult>, ICommandAuthenticationSession
        {
            Scheme = scheme;
            Payload = payload;
            RememberMe = rememberMe;
            return ValueTask.FromResult( command.CreateResult() );
        }
    }

    [Test]
    public async Task the_basic_login_command_opens_a_basic_session_Async()
    {
        var table = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>().ShouldNotBeNull();
        var cmd = SharedEngine.AutomaticServices.GetRequiredService<PocoDirectory>().Create<IBasicLoginCommand>( c =>
        {
            c.UserName = "Albert";
            c.Password = "the-password";
            c.RememberMe = true;
        } );
        var opener = new RecordingOpener();
        await table.HandleBasicLoginAsync( TestHelper.Monitor, cmd, opener );
        opener.Scheme.ShouldBe( "Basic" );
        opener.Payload.ShouldBe( new BasicLoginPayload( "Albert", "the-password" ) );
        opener.RememberMe.ShouldBeTrue();
    }
}
