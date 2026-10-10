using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.IO.Authentication.Basic;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Tests;

/// <summary>
/// Tests the "Basic" login provider of CK.DB.User.UserPassword (<see cref="UserPasswordLoginProvider"/>): its payload is the
/// <see cref="IBasicLoginCommand"/>.
/// </summary>
[TestFixture]
public class BasicLoginProviderTests
{
    static async Task<(int UserId, string UserName)> CreatePasswordUserAsync( string password )
    {
        var users = SharedEngine.Map.StObjs.Obtain<UserTable>().ShouldNotBeNull();
        var passwords = SharedEngine.Map.StObjs.Obtain<UserPasswordTable>().ShouldNotBeNull();
        using var ctx = new SqlStandardCallContext( TestHelper.Monitor );
        var userName = "Basic-" + Guid.NewGuid().ToString();
        var userId = await users.CreateUserAsync( ctx, 1, userName );
        await passwords.CreateOrUpdatePasswordUserAsync( ctx, 1, userId, password );
        return (userId, userName);
    }

    static IBasicLoginCommand Command( string userName, string password )
    {
        return SharedEngine.AutomaticServices.GetRequiredService<PocoDirectory>().Create<IBasicLoginCommand>( c =>
        {
            c.UserName = userName;
            c.Password = password;
        } );
    }

    [Test]
    public async Task basic_login_succeeds_with_the_right_password_Async()
    {
        var p = SharedEngine.AutomaticServices.GetRequiredService<UserPasswordLoginProvider>();
        p.ProviderNames.ShouldBe( ["Basic"] );
        SharedEngine.AutomaticServices.GetRequiredService<SqlLoginProvider>().ProviderNames.ShouldNotContain( "Basic", "The generic login provider doesn't handle it." );
        var (userId, userName) = await CreatePasswordUserAsync( "the-password" );

        var check = await p.LoginAsync( TestHelper.Monitor, "Basic", Command( userName, "the-password" ), actualLogin: false );
        check.IsSuccess.ShouldBeTrue();

        var r = await p.LoginAsync( TestHelper.Monitor, "Basic", Command( userName, "the-password" ) );
        r.IsSuccess.ShouldBeTrue();
        r.Actor!.ActorId.ShouldBe( userId );
        r.Actor.ActorName.ShouldBe( userName );
        r.Actor.Level.ShouldBe( AuthLevel.Critical );
        r.Actor.HasScheme( "Basic" ).ShouldBeTrue();
    }

    [Test]
    public async Task basic_login_fails_with_a_wrong_password_or_an_unknown_user_Async()
    {
        var p = SharedEngine.AutomaticServices.GetRequiredService<UserPasswordLoginProvider>();
        var (_, userName) = await CreatePasswordUserAsync( "the-password" );

        var wrong = await p.LoginAsync( TestHelper.Monitor, "Basic", Command( userName, "not-the-password" ) );
        wrong.IsSuccess.ShouldBeFalse();
        wrong.FailureCode.ShouldBe( (int)KnownLoginFailureCode.InvalidCredentials );
        wrong.FailureReason.ShouldNotBeNullOrWhiteSpace();

        var unknown = await p.LoginAsync( TestHelper.Monitor, "Basic", Command( "No-" + Guid.NewGuid(), "x" ) );
        unknown.IsSuccess.ShouldBeFalse();
        unknown.FailureCode.ShouldBeGreaterThan( 0 );

        await Util.Awaitable( () => p.LoginAsync( TestHelper.Monitor, "Basic", "not a command" ).AsTask() ).ShouldThrowAsync<ArgumentException>();
    }

    [Test]
    public async Task a_failed_login_never_logs_the_password_Async()
    {
        var p = SharedEngine.AutomaticServices.GetRequiredService<UserPasswordLoginProvider>();
        var (_, userName) = await CreatePasswordUserAsync( "the-password" );
        using( TestHelper.Monitor.CollectTexts( out var texts ) )
        {
            (await p.LoginAsync( TestHelper.Monitor, "Basic", Command( userName, "a-secret-attempt" ) )).IsSuccess.ShouldBeFalse();
            (await p.LoginAsync( TestHelper.Monitor, "Basic", Command( "No-" + Guid.NewGuid(), "another-secret-attempt" ) )).IsSuccess.ShouldBeFalse();
            texts.ShouldNotContain( t => t.Contains( "a-secret-attempt" ) || t.Contains( "another-secret-attempt" ) );
        }
    }

    [Test]
    public async Task the_basic_scheme_cannot_be_bound_by_a_login_Async()
    {
        var binder = SharedEngine.AutomaticServices.GetRequiredService<SqlAutoBindingAccountService>();
        var users = SharedEngine.AutomaticServices.GetRequiredService<SqlActorInfoProvider>();
        var (userId, userName) = await CreatePasswordUserAsync( "the-password" );
        var user = (await users.GetActorInfoAsync( TestHelper.Monitor, userId )).ShouldNotBeNull();
        var now = DateTime.UtcNow;
        var critical = AuthenticationInfo.Create( user, now.AddHours( 1 ), now.AddMinutes( 5 ), null, now );
        var c = new LoginContext( "Basic", Command( "someone-else", "x" ), critical );
        (await binder.BindAccountAsync( TestHelper.Monitor, c )).ShouldBeNull();
        c.ErrorId.ShouldBe( "User.AccountBinding.NotSupported", "A password is never bound by a login: its payload comes from the client." );
    }
}
