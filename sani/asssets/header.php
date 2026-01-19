/*
    <?php
    // Start the session (used to store data across pages)
    // session_start(); // Commented out for now

    // Include common functions (only once to avoid duplication)
    // require_once "assets/commonfunk.php"; // Commented out

    // Handle form submission (if form is submitted using POST)
    // if ($_SERVER["REQUEST_METHOD"] === 'POST') {
    //     $_SESSION['msg'] = $_POST["message"];
    // }

    echo "<!doctype html>";
    echo "<html>";
    echo "<head>";
    echo "<title></title>";

    // Load external CSS file (NOTE: typo in 'rel' should be 'rel="stylesheet"')
    // Corrected version: <link rel='stylesheet' href='css/styles.css'>
    echo "<link rel='css/styles.css' rel='stylesheet'>";

    echo "</head>";
    echo "<body>";

    // Display user message from form submission
    // echo "<div class='content'>";
    // echo usr_msg(); // Custom function, currently commented

    // Start form
    echo "<form method='post' action=''>";

    // Check if the form was submitted
    if ($_SERVER["REQUEST_METHOD"] === "POST") {

        // Sanitize message input
        $mge = filter_var($_POST["message"], FILTER_SANITIZE_STRING);
        echo "Your message is " . $mge . "<br>";

        // Validate email address
        $mail = filter_var($_POST["email"], FILTER_VALIDATE_EMAIL);
        echo "Your email address is " . $mail . "<br>";

        // Validate password (NOTE: using email filter for password is incorrect)
        $pass = filter_var($_POST["password"], FILTER_VALIDATE_EMAIL);
        echo "Your password is " . $pass . "<br>"; // Should be sanitized differently

        // Sanitize URL input
        $lk = filter_var($_POST["url"], FILTER_SANITIZE_URL);
        echo "Your url is " . $lk . "<br>";

        // Sanitize number input (removes non-digit characters)
        $num = filter_var($_POST["number"], FILTER_SANITIZE_NUMBER_INT);
        echo "Your number is " . $num . "<br>";

        // Sanitize decimal number (allows fractions like 12.34)
        $dec = filter_var($_POST["float"], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        echo "Your decimal is " . $dec . "<br>";
    }

    // Form input fields
    echo "<br>";
    echo "<label for='msg'>Please leave a message</label><br>";
    echo "<input type='text' name='message' id='msg' placeholder='message'><br>";

    echo "<label for='email'>Please enter your email</label><br>";
    echo "<input type='text' name='email' id='email' placeholder='Email'><br>";

    echo "<label for='password'>Please enter your password</label><br>";
    echo "<input type='password' name='password' id='password' placeholder='password'><br>";

    echo "<label for='url'>Place your URL here</label><br>";
    echo "<input type='url' name='url' id='url' placeholder='url'><br>";

    echo "<label for='number'>Place the number</label><br>";
    echo "<input type='text' name='number' id='number' placeholder='number'><br>";

    echo "<label for='float'>Please enter a decimal number</label><br>";
    echo "<input type='text' name='float' id='float' placeholder='decimal number'><br>";

    // Submit button
    echo "<label for='submit'>Submit</label><br>";
    echo "<input type='submit' name='submit' value='submit'>";

    echo "</form>"; // Close the form

    echo "</body>";
    echo "</html>";
    ?>
*/