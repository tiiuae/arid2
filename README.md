# Anonymous and Verifiable Remote Identification of Commercial Drones (ARID2)

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#introduction">Project Introduction</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

### Introduction

To enable enhanced accountability of Drones and Unmanned Aerial Vehicles (UAVs) operations, the US-based Federal Avionics Administration (FAA) recently published a new dedicated regulation, namely RemoteID, requiring all UAV operators to broadcast messages reporting their identity and location.

The enforcement of such a rule, mandatory by 2022, generated significant concerns on UAV operators, primarily because of privacy issues derived by the indiscriminate broadcast of the plain-text identity of the UAVs on the wireless channel.

First solutions to guarantee UAVs anonymity in the RemoteID settings are starting to appear in the literature (see [[Tedeschi et.al]](https://dl.acm.org/doi/10.1145/3485832.3485834)), but they fall short in guaranteeing the possibility to Critical Infrastructure (CI) operators to autonomously authenticate RemoteID messages. As a result, the FAA is heavily involved, not only in the deanonymization process but also in the authentication of received packets. Overall, such heavy involvement slows-down the chances of deployments of such solutions.

In this project, we plan to advance the state of the art by providing solutions for anonymous and verifiable remote identification of commercial drones and UAVs. To this aim, we plan to apply anonymous verifiable group signatures in the context of UAVs. Such cryptographic schemes allow members of a group to generate anonymous messages, whose authenticity can be verified by the receiving entities through the cryptographic verification of the association between the transmitting entity and the group. At the same time, such schemes allow the identification of the specific transmitter by a Trusted Party, when illegitimate activities are detected.

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

Our implementation, whose source code has been released as open-source, leverages popular libraries and tools, such as MAVSDK, and PBC Crypto Library, supported by the large variety of commercial UAVs that owns a GNU/Linux based mission computer. These features contribute to enhancing the impact of ARID2, demonstrating its deployability to improving the quality of the provided security services in real-world UAV systems.


### Prerequisites

_Hardware Requirements_

- A programmable drone with a GNU/Linux embedded operating system
- GPS Module (drone---on-board)
- MAVLink Telemetry Module (drone---on-board)
- Drone Controller compatible with the MAVLink telemetry protocol (optional)
- HackRF (or another SDR) to spoof GPS Signal Indoor - a TXCO is a plus
- AWUS036ACH - USB Type-C dual-band AC1200 WiFi adapter (1 for the Generic Receiver, 1 for the Transmitter, 1 for the Authority)

_Software Requirements_

- A laptop with a distro GNU/Linux (e.g. Ubuntu)
- Wireshark
- Visual Studio Code as IDE
- g++ compiler and the correspondent toolchain
- MAVSDK C++
- PBC
- Libtins
- gps-sdr-sim

<!-- ROADMAP -->
## Roadmap

- [x] Presentation
- [x] Porting the code on Raspberry Pi 4
- [x] Custom IEEE 802.11 PDU
- [x] ARID2 Wireshark Dissector
- [x] SHA 1 bugfix
- [x] FCS dirty bytes
- [ ] Energy Consumption Test
- [ ] Radio Timings/Energy Consumption Test

See the [open issues](issues) for a full list of proposed features (and known issues).

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/arid2`)
3. Commit your Changes (`git commit -m 'Add some Amazing Feature'`)
4. Push to the Branch (`git push origin feature/arid2`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the XXX License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Pietro Tedeschi - pietro dot tedeschi at tii dot ae 

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

Credit to ...
