using CK.Core;
using CK.DB.Actor;
using CK.DB.Auth;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Tests;

/// <summary>
/// Tests the CK.AuthenticationInfo basic login (CK.DB.Auth SqlLoginProvider with a BasicLoginPayload) on the real
/// UserPassword provider.
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

    [Test]
    public async Task basic_login_succeeds_with_the_right_password_Async()
    {
        var p = SharedEngine.AutomaticServices.GetRequiredService<SqlLoginProvider>();
        p.ProviderNames.ShouldContain( BasicLoginPayload.Scheme );
        var (userId, userName) = await CreatePasswordUserAsync( "the-password" );

        var check = await p.LoginAsync( TestHelper.Monitor, "Basic", new BasicLoginPayload( userName, "the-password" ), actualLogin: false );
        check.IsSuccess.ShouldBeTrue();

        var r = await p.LoginAsync( TestHelper.Monitor, "Basic", new BasicLoginPayload( userName, "the-password" ) );
        r.IsSuccess.ShouldBeTrue();
        r.User!.UserId.ShouldBe( userId );
        r.User.UserName.ShouldBe( userName );
        r.User.Level.ShouldBe( AuthLevel.Critical );
        r.User.HasScheme( "Basic" ).ShouldBeTrue();
    }

    [Test]
    public async Task basic_login_fails_with_a_wrong_password_or_an_unknown_user_Async()
    {
        var p = SharedEngine.AutomaticServices.GetRequiredService<SqlLoginProvider>();
        var (_, userName) = await CreatePasswordUserAsync( "the-password" );

        var wrong = await p.LoginAsync( TestHelper.Monitor, "Basic", new BasicLoginPayload( userName, "not-the-password" ) );
        wrong.IsSuccess.ShouldBeFalse();
        wrong.FailureCode.ShouldBe( (int)KnownLoginFailureCode.InvalidCredentials );
        wrong.FailureReason.ShouldNotBeNullOrWhiteSpace();

        var unknown = await p.LoginAsync( TestHelper.Monitor, "Basic", new BasicLoginPayload( "No-" + Guid.NewGuid(), "x" ) );
        unknown.IsSuccess.ShouldBeFalse();
        unknown.FailureCode.ShouldBeGreaterThan( 0 );
    }

    [Test]
    public async Task the_password_never_appears_in_the_payload_ToString_Async()
    {
        var payload = new BasicLoginPayload( "someone", "a-secret-password" );
        payload.ToString().ShouldNotContain( "a-secret-password" );
        await Task.CompletedTask;
    }
}
