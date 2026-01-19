<?php
session_start();

require_once "assets/commonfunk.php";
require_once "assets/dabco.php";

echo "<!DOCTYPE html>";

echo "<html>";

echo "<head>";
echo"<title>Rolsa Technologies</title>";

require_once "assets/header.php";
echo "</head>";
echo "<bod>";

echo "<p>Solar panels work by converting sunlight into electricity, 
allowing you to power your home with clean, renewable energy. 
By generating your own electricity, you reduce the amount you need to buy from the grid,
 which can cut your bills by 30–70% depending on your usage and system size. 
 Any extra energy can be stored in a battery or sold back to the grid, 
 giving you further savings or even income. Over time, 
 solar panels usually pay for themselves within about a decade, 
 while continuing to provide free energy for 25 years or more.</p>";

echo "<img src='images/Solar panel.jpg' alt='solar panel'>";

echo "<p>Green energy production is led by several major companies across wind, solar, hydro, and emerging technologies.
 Ørsted remains a global leader in offshore wind with most of its energy coming from renewables, 
 while Enel Green Power and Iberdrola operate large multinational portfolios spanning solar, wind, hydro, geothermal, and green hydrogen. 
 Neoen focuses entirely on renewable generation and large battery storage, and the UK’s Good Energy supports small-scale renewable projects. 
 Equipment manufacturers such as Vestas in wind and Sungrow in solar play key roles in scaling production. Globally, 
 the green-energy market continues to expand, driven by rising demand for clean electricity, 
 growing investment in storage to support intermittent sources like wind and solar, 
 and increasing development of green hydrogen. Despite strong growth, challenges remain, including variability in renewable output, 
 high storage costs, regulatory uncertainty, and supply-chain constraints for technologies like batteries and solar panels.</p>";

echo"<img src='images/Green Energy.jpg' alt='Green Energy Production'>";

echo"<p>Reducing your carbon footprint involves making consistent, 
everyday choices that lower the amount of greenhouse gases you generate, 
starting with energy use by choosing renewable electricity, improving home insulation, 
and switching to efficient appliances to cut waste. Transportation changes—like driving less, 
carpooling, choosing public transit, biking or walking, and when possible switching to an electric or hybrid vehicle—also make a large impact. 
Diet and consumption habits matter too, with reducing meat and dairy, minimizing food waste, 
and buying locally produced foods all lowering emissions. Opting for durable, 
repairable products, reducing single-use items, and recycling correctly help decrease the carbon cost of manufacturing.
 Meanwhile, mindful lifestyle adjustments such as lowering water use, avoiding unnecessary flights, 
 and supporting companies or policies that prioritize sustainability reinforce long-term climate benefits. 
 Together, these actions create a meaningful and cumulative reduction in your personal carbon footprint.</p>";

echo"<img src='images/carbon footprint.jpg' alt='Carbon Footprint'>";

echo"</body>";
require_once "assets/footer.php";
echo"</html>";
