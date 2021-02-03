NOTE: the project is still in its early-stages, so the API may change significantly in the future

The BAF Wallet exposes the following HTTP Endpoints, each expecting arguments in the form of JSON
* `/signup`:
  * description: create a "web2" account in the BAF wallet
  * expected request body:
  ```json
    {
      "email": "some_email@some_domain.com",
      "password": "initial_password"
    }
  ```
  * responses:
    * `200`: succeeded in creating new BAF account, empty body
    * `422`: invalid email or password is too short. body:
    ```json
    {
      "error": "'invalid email' or 'password too short'"
    }
    ```
    * `409`: account already exists. body:
    ```json
    {
      "error": "accound already exists"
    }
    ```
    * `500`: internal server error
* `/login`:
  * description: login to an existing "web2" account
  * expected request body:
  ```json
    {
      "email": "some_email@some_domain.com",
      "password": "password"
    }
  ```
  * responses:
    * `200`: login successful, body should look like:
    ```json
      {
        "token": "authentication_token"
      }
    ```
    * `401`: login failed
    * `404`: any other error 
* `/adminRpc`: protected JSON-RPC 2.0 interface for admin-level actions
* `/rpc`: JSON-RPC 2.0 interface for wallet actions, requires a user to be signed in to their "web2" account to use

`/adminRpc` methods:
  * `verify`: marks a user's identity as "verified", allowing them to create exclusively or link a NEAR account, and initialize it with 1.1 + gas allowance NEAR from the wallet's balance
    * expected reuest body (will probably require other information eventually):
    ```json
    {
      "email": "some_email@some_domain.com"
    }
    ```
    * result: empty if successful
    * error: 
    ```json
    {
      "error": "some_helpful_error_description"
    }
    ```

`/rpc` methods
  * `createNearAccount`: create a new NEAR account and initialize it with the wallet's funds
    * params: none, as we already have the user's ID from JWT
    * result: empty if successful
    * error: 
    ```json
    {
      "error": "some_user_facing_error_description"
    }
    ```
  * `linkNearAccount`: link an existing NEAR account to the BAF wallet. The BAF wallet will not store the private keys or provide authentication, it will just send 1.1 + gas allowance NEAR to it.
    * params:
    ```json
    {
      "accountId": "linked_account_id"
    }
    ```
    * result: empty if successful
    * error: 
    ```json
    {
      "error": "some_user_facing_error_description"
    }
    ```
  * `addAccessKey`: add an access key to the user's NEAR account. Fails if the linked account is non-custodial (i.e. they linked rather than created an account).
    * params: follows serde's [externally-tagged enum](https://serde.rs/enum-representations.html#externally-tagged) representation for a to-be-created enum that captures the format of NEAR's two access key types - Full, and FnCall
    * result: empty if successful
    * error: 
    ```json
    {
      "error": "some_user_facing_error_description"
    }
    ```
