# Front Project

This project is a Next.js front-end for interacting with the Tracker service. It provides a web interface built with modern React and Tailwind CSS.

## Requirements

- **Node.js**: 18.17 or later (developed with v20.19.4)
- **Next.js**: 14.2.3

## Environment Variables

Create a `.env` file based on the example below. These variables configure the Tracker API connection:

- `TRACKER_BASE_URL` – base URL of the Tracker API.
- `TRACKER_OAUTH_TOKEN` – OAuth token for authentication.
- `TRACKER_ORG_ID` – organization identifier in Tracker.

Example `.env.example`:

```
TRACKER_BASE_URL=https://tracker.example.com
TRACKER_OAUTH_TOKEN=replace-with-token
TRACKER_ORG_ID=123456
```

## Scripts

- `npm run dev` – start development server with hot reload.
- `npm run build` – build the production bundle.
- `npm run start` – run the production server after building.

