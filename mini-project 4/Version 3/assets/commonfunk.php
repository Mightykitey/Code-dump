<?php
// Function to check if a given email already exists in the 'patients' table
function only_patients($conn, $email)
{
    try {
        // Prepare SQL statement to search for a patient by email
        $sql = "SELECT email FROM patients WHERE email = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bindParam(1, $email);  // Bind email parameter
        $stmt->execute();             // Execute the SQL query

        $result = $stmt->fetch(PDO::FETCH_ASSOC);  // Fetch one matching row

        // Return true if a match is found, false otherwise
        return $result ? true : false;

    } catch (PDOException $e) {
        // Log and rethrow database errors
        error_log("Error in patient lookup: " . $e->getMessage());
        throw $e;
    }
}


// Function to insert a new patient record into the database
function new_patients($conn, $post)
{
    try {
        // SQL query with placeholders for inserting new patient data
        $sql = "INSERT INTO patients (fname, lname, dob, email, pwd) VALUES (?,?,?,?,?)";
        $stmt = $conn->prepare($sql);

        // Bind form data to the SQL query
        $stmt->bindParam(1, $post['fname']);
        $stmt->bindParam(2, $post['lname']);
        $stmt->bindParam(3, $post['dob']);
        $stmt->bindParam(4, $post['email']);

        // Securely hash password before storing
        $hpwd = password_hash($post['pwd'], PASSWORD_DEFAULT);
        $stmt->bindParam(5, $hpwd);

        // Execute the insert query
        $stmt->execute();
        $conn = null; // Close connection (optional)
        return true;

    } catch (PDOException $e) {
        // Log and rethrow database-related exceptions
        error_log('Database error: ' . $e->getMessage());
        throw new Exception('Database error: ' . $e->getMessage());
    } catch (Exception $e) {
        // Log and rethrow any other type of error
        error_log('Error: ' . $e->getMessage());
        throw new Exception('Error: ' . $e->getMessage());
    }
}


// Function to show and clear a session-based user message
function user_message()
{
    if (isset($_SESSION['usermessage'])) {
        $message = "<p>" . $_SESSION['usermessage'] . "</p>";
        unset($_SESSION['usermessage']); // Remove message after displaying
        return $message;
    } else {
        return "";
    }
}


// Function to check user login credentials
function login($conn, $post)
{
    $sql = "SELECT patient_id, pwd FROM patients WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $post);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $conn = null;

    // Return patient data if found, otherwise false
    return $result ? $result : false;
}


// Function to record an audit log entry (tracks user activity)
function audititor($conn, $patid, $code, $ldesc)
{
    $sql = "INSERT INTO audit (date, patient_id, code, longdesc) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $date = date("Y-m-d");  // Current date
    $stmt->bindParam(1, $date);
    $stmt->bindParam(2, $patid);
    $stmt->bindParam(3, $code);
    $stmt->bindParam(4, $ldesc);

    $stmt->execute();
    $conn = null;
    return true;
}


// Function to check if password session variable contains an error
function hasPassword($string)
{
    if (!str_contains($_SESSION['password'], "ERROR")) {
        $string = "USER MESSAGE: " . $_SESSION['password'];
        return true;
    } else {
        $string = "USER MESSAGE: " . $_SESSION['password'];
        return false;
    }
}


// Function to save a new booking to the database
function commit_bookimg($conn, $epoch)
{
    $sql = "INSERT INTO booking (patient_id, staff_id, appdate, bookdon) VALUES (?,?,?,?)";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_SESSION['patid']);
    $stmt->bindParam(2, $_POST['staff']);
    $stmt->bindParam(3, $epoch);

    $temp = time(); // Record booking creation time
    $stmt->bindParam(4, $temp);

    $stmt->execute();
    $conn = null;
    return true;
}


// Function to get all appointments for the logged-in patient
function apt_getter($conn)
{
    $sql = "SELECT b.booking_id, b.appdate, b.bookdon, s.job, s.fname, s.lname, s.rom 
            FROM booking b 
            JOIN staff s ON b.staff_id = s.staff_id 
            WHERE b.patient_id = ? 
            ORDER BY b.appdate ASC";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $_SESSION['patid']);
    $stmt->execute();

    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $conn = null;

    // Return all appointments or false if none exist
    return $result ? $result : false;
}


// Function to cancel an appointment
function cancel_apt($conn, $aptid)
{
    $sql = "DELETE FROM booking WHERE booking_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $aptid);
    $stmt->execute();
    $conn = null;
    return true;
}


// Function to fetch one appointment by its ID
function apt_fetch($conn, $aptid)
{
    $SQL = "SELECT * FROM booking WHERE booking_id = ?";
    $stmt = $conn->prepare($SQL);
    $stmt->bindParam(1, $aptid);
    $stmt->execute();

    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $conn = null;
    return $result;
}


// Function to update appointment details (staff/time)
function apt_update($conn, $aptid, $aptime)
{
    $sql = "UPDATE booking SET staff_id = ?, appdate = ?, bookdon = ? WHERE booking_id = ?";
    $stmt = $conn->prepare($sql);

    $stmt->bindParam(1, $_POST['staff']);
    $stmt->bindParam(2, $aptime);
    $stmt->bindParam(3, $aptid); // ⚠️ Possibly a bug: should bind bookdon, not aptid
    $stmt->execute();

    $conn = null;
    return true;
}


// Function to get a patient's profile and audit records
function pro_getter($conn)
{
    $sql = "SELECT p.patient_id, p.fname, p.lname, p.dob, p.email, p.pwd, a.code, a.date, a.longdesc
            FROM patients p 
            JOIN audit a ON p.patient_id = a.patient_id 
            WHERE p.patient_id = ? 
            ORDER BY a.date ASC";

    $stmt = $conn->prepare($sql);
    $stmt->bindParam(1, $_SESSION['patid']);
    $stmt->execute();

    $result = $stmt->fetchAll(PDO::FETCH_ASSOC);
    $conn = null;

    return $result ? $result : false;
}
?>
