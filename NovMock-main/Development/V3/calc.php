<?php

$result = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    try {


        $electricity = floatval($_POST["electricity"] ?? 0);
        $car = floatval($_POST["car"] ?? 0);
        $flights = floatval($_POST["flights"] ?? 0);

        $electricityFactor = 0.475;
        $carFactor = 0.192;
        $flightsFactor = 90;

        $total =
            $electricity * $electricityFactor * 12 +
            $car * $carFactor * 52 +
            $flights * $flightsFactor;

        $result = "Estimated yearly CO₂ emissions: " . number_format($total, 1) . " kg";
    }
    catch(PDOException $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: booking.php');
        exit();
    } catch(Exception $e){
        $_SESSION["usermessage"] = "Error: " . $e->getMessage();
        header('Location: booking.php');
        exit();
    }
}


echo "<!doctype html>";
echo "<html>";

echo "<head>";
echo "<title>Rolsa Technologies</title>";
require_once "assets/header.php";
echo "</head>";

echo "<body>";


echo "<div class='container'>";

echo "<form method='POST' class='carbon-calculator'>";
echo "    <h2>Carbon Footprint Calculator</h2>";

echo "    <label>Electricity Usage (kWh per month):</label>";
echo "    <input name='electricity' type='number' placeholder='e.g. 300'>";

echo "    <label>Car Travel (km per week):</label>";
echo "    <input name='car' type='number' placeholder='e.g. 100'>";

echo "    <label>Flights (hours per year):</label>";
echo "    <input name='flights' type='number' placeholder='e.g. 20'>";

echo "    <button type='submit'>Calculate</button>";

echo "    <h3>" . $result . "</h3>";
echo "</form>";


echo "</div>";

echo"</body>";
require_once "assets/footer.php";
echo "</html>";
