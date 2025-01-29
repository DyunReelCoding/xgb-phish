chrome.tabs.onActivated.addListener((activeInfo) => {
    chrome.tabs.get(activeInfo.tabId, (tab) => {
        const url = tab.url;
        console.log("Active tab URL:", url);

        // Send the URL to the Flask API
        fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: url }),
        })
        .then((response) => response.json())
        .then((data) => {
            console.log("Response from API:", data);
            
            // If the website is phishing (prediction = 1)
            if (data.prediction === 1) {
                // Show a notification
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png',  // Add an icon for the notification
                    title: 'Warning: Phishing Site Detected!',
                    message: `The website ${url} is classified as phishing.`,
                    buttons: [
                        { title: "Go Back" },
                        { title: "Continue" }
                    ],
                    priority: 2
                }, (notificationId) => {
                    console.log("Notification created with ID: " + notificationId);
                });

                // Handle notification button clicks
                chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
                    if (buttonIndex === 0) {
                        // Go back to the previous page (navigate to the previous tab)
                        chrome.tabs.goBack();
                    } else if (buttonIndex === 1) {
                        // Continue on the same tab (do nothing, just close the notification)
                        chrome.notifications.clear(notificationId);
                    }
                });
            }
        })
        .catch((error) => console.error("Error:", error));
    });
});
