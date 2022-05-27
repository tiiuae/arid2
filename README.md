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
