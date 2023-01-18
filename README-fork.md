# Issue addressed by this fork

Microsoft Advertising API returns access token with fewer scopes than initially
granted after using refresh token to obtain a new access token.

It turned around, that it happens because "golang.org/x/oauth2" does not send
scope parameter on refresh request. 

It seems, that without this parameter Microsoft API returns access token with
default minimal set of scopes - not one was provided initially.

When request is made with this parameter, it forces Microsoft API to return
access token with correct scope.

# History of similar issues and PRs previously submitted to upstream project

https://github.com/golang/oauth2/issues/234

https://github.com/golang/oauth2/pull/322
https://go-review.googlesource.com/c/oauth2/+/135935

https://github.com/golang/oauth2/pull/448
https://go-review.googlesource.com/c/oauth2/+/264037

https://github.com/golang/oauth2/pull/509
https://go-review.googlesource.com/c/oauth2/+/332749

https://github.com/golang/oauth2/pull/540
https://go-review.googlesource.com/c/oauth2/+/381916

https://github.com/golang/oauth2/pull/559
https://go-review.googlesource.com/c/oauth2/+/394696

https://github.com/golang/oauth2/pull/579
https://go-review.googlesource.com/c/oauth2/+/421174

https://github.com/golang/oauth2/pull/598

At this point it's obvious that changes have slim chances to make into
upstream, because of maintainers' position, best stated
[here](https://github.com/golang/oauth2/issues/112#issuecomment-101063921):

> We are not willing to implement workarounds for each broken OAuth 2.0
> implementation. If this is a blocker for you, please maintain your own of
> the oauth2 package with the necessary patches.

It equally unlikely to persuade Microsoft to make the change.
So, here we are.

# Some arguments why this option should be supported

According to RFC, it seems, that issue is indeed on Microsoft side. But looking
at history it is clear that it persisted for quite a long already. Many PRs
have been submitted (and rejected or ignored) to the upstream project during
this time. It seems, that both sides are stubborn to change their mind.

Obviously, we (application programmers) are not in position of endlessly
arguing with Microsoft and Google about correct RFC implementation. We need
some practical workaround to make our work at hands. But just in case, I'll
provide couple of arguments in support of this change.

First of all, RFC 6749 sections 3.3 and 6 says, that indeed this parameter is
optional. But "optional" for me sounds like we should have an option to provide
it, if we have to. So, implementation should not prohibit us to do it.

Second, taking aside Microsoft issue, RFC allows to either send the same or
fewer scopes. May be it is a rare use case, but it is in RFC and upstream
implementation does not address it.

