# KindeApi::CreateUserResponse

## Properties

| Name | Type | Description | Notes |
| ---- | ---- | ----------- | ----- |
| **id** | **String** | Unique ID of the user in Kinde. | [optional] |
| **created** | **Boolean** | True if the user was successfully created. | [optional] |
| **identities** | [**Array&lt;UserIdentity&gt;**](UserIdentity.md) |  | [optional] |

## Example

```ruby
require 'kinde_api'

instance = KindeApi::CreateUserResponse.new(
  id: null,
  created: null,
  identities: null
)
```

