We avoid hardcoded strings and use references to symbols, such as constants, enums, or class names.
We also avoid using magic numbers and prefer to use named constants or enums instead.
We use Laravel's built-in features and libraries whenever possible.. 

We use $request->getFingerprint() to get the fingerprint of the request and use it to identify the user. This macro is defined in CitadelServiceProvider.php. 

It is absolutely forbidden to add special code that makes the test pass or for test cases. All code must work in real work conditions and for all inputs. 
 