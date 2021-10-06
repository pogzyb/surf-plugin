/*
Description: Browser Plugin for the Surf Phish Detection API (https://deep.surf).
Author:  Joe Obarzanek
Contact: mailman@deep.surf
*/
import './App.css';

const API_VERSION = 'v1'

const ok = '<span class="text-info"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-cursor" viewBox="0 0 16 16"><path d="M14.082 2.182a.5.5 0 0 1 .103.557L8.528 15.467a.5.5 0 0 1-.917-.007L5.57 10.694.803 8.652a.5.5 0 0 1-.006-.916l12.728-5.657a.5.5 0 0 1 .556.103zM2.25 8.184l3.897 1.67a.5.5 0 0 1 .262.263l1.67 3.897L12.743 3.52 2.25 8.184z"/></svg> Low Risk</span>';
const phish = '<span class="text-warning"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle-fill" viewBox="0 0 16 16"><path d="M8.982 1.566a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566zM8 5c.535 0 .954.462.9.995l-.35 3.507a.552.552 0 0 1-1.1 0L7.1 5.995A.905.905 0 0 1 8 5zm.002 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2z"/></svg> Potential Phish</span>';
const whitelist = '<span class="text-success"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-circle" viewBox="0 0 16 16"><path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14zm0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16z"/><path d="M10.97 4.97a.235.235 0 0 0-.02.022L7.477 9.417 5.384 7.323a.75.75 0 0 0-1.06 1.06L6.97 11.03a.75.75 0 0 0 1.079-.02l3.992-4.99a.75.75 0 0 0-1.071-1.05z"/></svg> Safe Site</span>';
const blacklist = '<span class="text-danger"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bricks" viewBox="0 0 16 16"><path d="M0 .5A.5.5 0 0 1 .5 0h15a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H14v2h1.5a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H14v2h1.5a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H.5a.5.5 0 0 1-.5-.5v-3a.5.5 0 0 1 .5-.5H2v-2H.5a.5.5 0 0 1-.5-.5v-3A.5.5 0 0 1 .5 6H2V4H.5a.5.5 0 0 1-.5-.5v-3zM3 4v2h4.5V4H3zm5.5 0v2H13V4H8.5zM3 10v2h4.5v-2H3zm5.5 0v2H13v-2H8.5zM1 1v2h3.5V1H1zm4.5 0v2h5V1h-5zm6 0v2H15V1h-3.5zM1 7v2h3.5V7H1zm4.5 0v2h5V7h-5zm6 0v2H15V7h-3.5zM1 13v2h3.5v-2H1zm4.5 0v2h5v-2h-5zm6 0v2H15v-2h-3.5z"/></svg> Known Threat</span>';

function classificationBadge(prediction) {
  if (prediction === 1) {
    return blacklist;
  } else if (prediction >= 0.7) {
    return phish;
  } else if (prediction < 0.7 && prediction > 0) {
    return ok;
  } else if (prediction === 0) {
    return whitelist;
  }
}

function scan(e) {
  e.preventDefault();
  // hide status
  document.getElementById("status").innerHTML = "";
  // hide form
  let form = document.getElementById("scanForm");
  form.classList.add("hide");
  // show loader
  let loader = document.getElementById("loader");
  loader.classList.remove("hide");
  // request data 
  let payload = {
    'url': form.elements['submittedURL'].value, 
    'screenshot': true,
    // Must set these to true, so that the entire report will be saved properly.
    'url_parsed': true,
    'whois_query': true,
    'whois_parsed': true,
    'html': true,
    'network': true  
  }
  // scan-plugin will only the return uuid, prediction, and screenshot
  fetch('https://engine.deep.surf/api/' + API_VERSION + '/scanner/scan-plugin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
  // check response
  .then(response => {
    if (!response.ok) {
      throw new Error(response.status);
    } else {
      return response.json()
    }
  })
  // display report
  .then(data => {
    loader.classList.add("hide");
    document.getElementById("report").classList.remove("hide");
    // set screenshot
    document.getElementById("screenshot").src = "data:image/png;base64, " + data["screenshot"];
    // set prediction badge
    document.getElementById("prediction").innerHTML = classificationBadge(data["prediction"]);
    // set external report link
    document.getElementById("link").href = "https://deep.surf/report?uuid=" + data["uuid"];
  })
  // handle errors
  .catch(error => {
    clear();
    let status = document.getElementById("status");
    if (error === 503) {
      status.innerHTML = "<small>Could not connect to that URL.</small>";
    } else {
      status.innerHTML = "<small>Unknown error. Try again...</small>";
    }
  });
}

function clear() {
  // resets the UI to prepare for another submission
  document.getElementById("scanForm").classList.remove("hide");
  document.getElementById("report").classList.add("hide");
  document.getElementById("prediction").innerHTML = "";
  document.getElementById("link").href = "https://deep.surf/";
  document.getElementById("screenshot").src = "#";
  document.getElementById("status").innerHTML = "";
  document.getElementById("loader").classList.add("hide");
}

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" fill="currentColor" className="bi bi-tsunami" viewBox="0 0 16 16">
          <path d="M.036 12.314a.5.5 0 0 1 .65-.278l1.757.703a1.5 1.5 0 0 0 1.114 0l1.014-.406a2.5 2.5 0 0 1 1.857 0l1.015.406a1.5 1.5 0 0 0 1.114 0l1.014-.406a2.5 2.5 0 0 1 1.857 0l1.015.406a1.5 1.5 0 0 0 1.114 0l1.757-.703a.5.5 0 1 1 .372.928l-1.758.703a2.5 2.5 0 0 1-1.857 0l-1.014-.406a1.5 1.5 0 0 0-1.114 0l-1.015.406a2.5 2.5 0 0 1-1.857 0l-1.014-.406a1.5 1.5 0 0 0-1.114 0l-1.015.406a2.5 2.5 0 0 1-1.857 0l-1.757-.703a.5.5 0 0 1-.278-.65zm0 2a.5.5 0 0 1 .65-.278l1.757.703a1.5 1.5 0 0 0 1.114 0l1.014-.406a2.5 2.5 0 0 1 1.857 0l1.015.406a1.5 1.5 0 0 0 1.114 0l1.014-.406a2.5 2.5 0 0 1 1.857 0l1.015.406a1.5 1.5 0 0 0 1.114 0l1.757-.703a.5.5 0 1 1 .372.928l-1.758.703a2.5 2.5 0 0 1-1.857 0l-1.014-.406a1.5 1.5 0 0 0-1.114 0l-1.015.406a2.5 2.5 0 0 1-1.857 0l-1.014-.406a1.5 1.5 0 0 0-1.114 0l-1.015.406a2.5 2.5 0 0 1-1.857 0l-1.757-.703a.5.5 0 0 1-.278-.65zM2.662 8.08c-.456 1.063-.994 2.098-1.842 2.804a.5.5 0 0 1-.64-.768c.652-.544 1.114-1.384 1.564-2.43.14-.328.281-.68.427-1.044.302-.754.624-1.559 1.01-2.308C3.763 3.2 4.528 2.105 5.7 1.299 6.877.49 8.418 0 10.5 0c1.463 0 2.511.4 3.179 1.058.67.66.893 1.518.819 2.302-.074.771-.441 1.516-1.02 1.965a1.878 1.878 0 0 1-1.904.27c-.65.642-.907 1.679-.71 2.614C11.076 9.215 11.784 10 13 10h2.5a.5.5 0 0 1 0 1H13c-1.784 0-2.826-1.215-3.114-2.585-.232-1.1.005-2.373.758-3.284L10.5 5.06l-.777.388a.5.5 0 0 1-.447 0l-1-.5a.5.5 0 0 1 .447-.894l.777.388.776-.388a.5.5 0 0 1 .447 0l1 .5a.493.493 0 0 1 .034.018c.44.264.81.195 1.108-.036.328-.255.586-.729.637-1.27.05-.529-.1-1.076-.525-1.495-.426-.42-1.19-.77-2.477-.77-1.918 0-3.252.448-4.232 1.123C5.283 2.8 4.61 3.738 4.07 4.79c-.365.71-.655 1.433-.945 2.16-.15.376-.301.753-.463 1.13z"/>
        </svg>
        <h1 className="mt-0 mb-0">Surf</h1>
        <p className="lead mt-0 mb-0">URL Scanner</p>
        <div id="content">
          {/* status */}
          <p id="status" className="text-warning"></p>
          {/* form */}
          <form onSubmit={scan} id="scanForm">
            <input className="d-block form-control rounded-pill shadow" type="url" name="submittedURL"
              placeholder="http://a-suspicious.url.to?scan=yes" required>
            </input>
            <button className="d-inline-block mt-1 submit-btn rounded-pill shadow" type="submit">
              <span className="submit-text">Scan »</span>
            </button>
          </form>
          {/* report */}
          <div id="report" className="hide">
            {/* prediction */}
            <h4 className="p-2 mb-5px mt-0">
              <span id="prediction" className="pill rounded-pill"></span> 
              {/* report btn */}
              <span className="pill rounded-pill bg-light">
                <a id="link" className="text-dark no-decoration" target="_blank" rel="noreferrer" href="https://deep.surf/">  
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" className="bi bi-arrow-up-right-circle" viewBox="0 0 16 16">
                    <path fillRule="evenodd" d="M1 8a7 7 0 1 0 14 0A7 7 0 0 0 1 8zm15 0A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM5.854 10.803a.5.5 0 1 1-.708-.707L9.243 6H6.475a.5.5 0 1 1 0-1h3.975a.5.5 0 0 1 .5.5v3.975a.5.5 0 1 1-1 0V6.707l-4.096 4.096z"/>
                  </svg>
                </a>
              </span> 
              {/* reset btn */}
              <span className="ml-1 pill rounded-pill bg-light">
                <a className="text-dark" href="#clear" onClick={clear}>
                  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" className="bi bi-arrow-counterclockwise" viewBox="0 0 16 16">
                    <path fillRule="evenodd" d="M8 3a5 5 0 1 1-4.546 2.914.5.5 0 0 0-.908-.417A6 6 0 1 0 8 2v1z"/>
                    <path d="M8 4.466V.534a.25.25 0 0 0-.41-.192L5.23 2.308a.25.25 0 0 0 0 .384l2.36 1.966A.25.25 0 0 0 8 4.466z"/>
                  </svg>
                </a>
              </span>
            </h4>
            {/* screenshot */}
            <img id="screenshot" alt="screenshot" className="rounded-img" src="#"></img>
          </div>
          {/* loader */}
          <div id="loader" className="mt-0 hide">
            <span className="loader throbber-loader">Loading&#8230;</span>
          </div>
        </div>
        <hr className="mt-3" width="75"/>
        {/* footer and version info */}
        <small className="footer-text">v{process.env.REACT_APP_VERSION_TAG} • {process.env.REACT_APP_GIT_HASH}</small>
      </header>
    </div>
  );
}

export default App;
