<?php
function dabco_insert() {
    /**
     *IMPORTANT SECURITY NOTE:
     * The following credentials ($servername, $dbusername, $dbpassword) are hardcoded in plain text.
     * This is NOT recommended for real-world applications or production environments, because:
     *   - It exposes sensitive credentials.
     *   - "root" should not be used as a database user in production — it has full admin rights.
     *   - These values should be stored in environment variables or a secure config file.
     * However, due to **school network limitations**, this simplified approach is used here.
     */

    $servername = "localhost";     // Server address (localhost in this case)
    $dbusername = "root";          // Using 'root' is insecure in production
    $dbpassword = '';              // Empty password — not secure
    $dbname = "rza"; // Name of the database to connect to

    try {
        // Create a new PDO connection to the MySQL database
        $conn = new PDO("mysql:host=$servername;port=3306;dbname=$dbname", $dbusername, $dbpassword);

        // Set PDO to throw exceptions when database errors occur
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Return the database connection object
        return $conn;
    } catch (PDOException $e) {
        // Log the error to the server logs for debugging (not shown to users)
        error_log("Database error in dabco_insert: " . $e->getMessage());

        // Re-throw the exception so it can be handled elsewhere
        throw $e;
    }
}

// Database connection function
function dabco_select()
{
    /**
     *IMPORTANT SECURITY NOTE:
     * The following credentials ($servername, $dbusername, $dbpassword) are hardcoded in plain text.
     * This is NOT recommended for real-world applications or production environments, because:
     *   - It exposes sensitive credentials.
     *   - "root" should not be used as a database user in production — it has full admin rights.
     *   - These values should be stored in environment variables or a secure config file.
     * However, due to **school network limitations**, this simplified approach is used here.
     */

    $servername = "localhost";     // Server address (localhost in this case)
    $dbusername = "root";          // Using 'root' is insecure in production
    $dbpassword = '';              // Empty password — not secure
    $dbname = "rza"; // Name of the database to connect to

    try {
        // Create a new PDO connection to the MySQL database
        $conn = new PDO("mysql:host=$servername;port=3306;dbname=$dbname", $dbusername, $dbpassword);

        // Set PDO to throw exceptions when database errors occur
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Return the database connection object
        return $conn;
    } catch (PDOException $e) {
        // Log the error to the server logs for debugging (not shown to users)
        error_log("Database error in dabco_select: " . $e->getMessage());

        // Re-throw the exception so it can be handled elsewhere
        throw $e;
    }
}
function dabco_update(){
    $servername = "localhost";  //sets servername

    $dbusername = "root"; // had to change this variable name as it fought against the admin reg and user reg

    $dbpassword = "";  //password for database useraccount

    $dbname = "rza";  //database name to connect to

    try {  //attempt this block of code, catching an error
        $conn = new PDO("mysql:host=$servername;port=3306;dbname=$dbname", $dbusername, $dbpassword);  // creates a PDO connection to the database
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); //sets error modes
        return $conn;
    } catch(PDOException $e) {  //catch statement if it fails
        error_log("Database error in super_checker: " . $e->getMessage());
        // Throw the exception
        throw $e; // Re-throw the exception  // outputs the error
    }
}

function dabco_delete(){
    $servername = "localhost";  //sets servername

    $dbusername = "root"; // had to change this variable name as it fought against the admin reg and user reg

    $dbpassword = "";  //password for database useraccount

    $dbname = "rza";  //database name to connect to

    try {  //attempt this block of code, catching an error
        $conn = new PDO("mysql:host=$servername;port=3306;dbname=$dbname", $dbusername, $dbpassword);  // creates a PDO connection to the database
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); //sets error modes
        return $conn;
    } catch(PDOException $e) {  //catch statement if it fails
        error_log("Database error in super_checker: " . $e->getMessage());
        // Throw the exception
        throw $e; // Re-throw the exception  // outputs the error
    }
}
