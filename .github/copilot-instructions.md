We avoid hardcoded strings and use references to symbols, such as constants, enums, or class names.
We also avoid using magic numbers and prefer to use named constants or enums instead.
We use Laravel's built-in features and libraries whenever possible, and we prefer to use Laravel's built-in features and libraries over third-party packages. 

We use $request->getFingerprint() to get the fingerprint of the request and use it to identify the user. This macro is defined in CitadelServiceProvider.php. 
It is forbidden to include special code for test cases in the codebase. We instead, we write correct code and use the test cases to verify that the code works as expected.
 