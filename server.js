const express = require('express');
const axios = require('axios');

const app = express();

app.use(express.json());

const API_KEY = process.env.GOOGLE_API_KEY;

// Главная страница
app.get('/', (req, res) => {
    res.send('Safe Check Backend is running');
});

// Проверка URL через Google Safe Browsing
app.get('/check', (req, res) => {
    res.json({
        message: 'Use POST request with JSON body { url }'
    });
});

app.post('/check', async (req, res) => {
    try {
        const { url } = req.body;

        if (!url) {
            return res.status(400).json({
                success: false,
                message: 'URL is required'
            });
        }

        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
            {
                client: {
                    clientId: 'safe-check',
                    clientVersion: '1.0.0'
                },
                threatInfo: {
                    threatTypes: [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    platformTypes: ['ANY_PLATFORM'],
                    threatEntryTypes: ['URL'],
                    threatEntries: [{ url }]
                }
            }
        );

        const threats = response.data.matches || [];

        res.json({
            success: true,
            safe: threats.length === 0,
            threats
        });

    } catch (error) {
        console.error(error.response?.data || error.message);

        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
