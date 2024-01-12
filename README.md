# BlazorAuthIssue

Changes from default Scaffold (authorization with individual accounts)

Register.razor - Adds the claim for my-group for every registered user

Counter.razor - URL slightly changed to include the groupId and Authorization check

App.Razor - Sets renderMode for all pages that are not Identity pages to InteractiveServer

Program.cs - Added RequirementHandler and a GroupPolicy - This is where things goes wrong.