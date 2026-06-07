package analizasieci.windowsControls;

import analizasieci.Solution;
import analizasieci.packetCapture.MyPacket;
import analizasieci.packetCapture.PacketLookupRow;
import analizasieci.packetCapture.packetLayers.ProtocolLayer;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.collections.transformation.FilteredList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.text.Font;
import javafx.stage.Stage;

import java.util.Map;

public class PacketLookupWindowController {

    private Solution program;

    @FXML private TableView<PacketLookupRow> packetList;
    @FXML private TableColumn<PacketLookupRow, Integer> colNr;
    @FXML private TableColumn<PacketLookupRow, String> colSource;
    @FXML private TableColumn<PacketLookupRow, String> colDestination;
    @FXML private TableColumn<PacketLookupRow, String> colProtocol;
    @FXML private TableColumn<PacketLookupRow, Integer> colLength;
    @FXML private TableColumn<PacketLookupRow, String> colInfo;

    @FXML private TreeView<String> protocolTree;
    @FXML private TextArea hexDump;

    @FXML private TextField filterTextBox;

    @FXML private Button button1;
    @FXML private MenuItem fileQuit;

    private final ObservableList<PacketLookupRow> packetData = FXCollections.observableArrayList();
    private final FilteredList<PacketLookupRow> filteredData = new FilteredList<>(packetData, p -> true);
    public void setProgram(Solution program) {
        this.program = program;
        program.listeningLoop(this::addPacketToTable);
    }

    @FXML
    public void initialize() {
        System.out.println("tesst");
        colNr.setCellValueFactory(new PropertyValueFactory<>("id"));
        colSource.setCellValueFactory(new PropertyValueFactory<>("source"));
        colDestination.setCellValueFactory(new PropertyValueFactory<>("destination"));
        colProtocol.setCellValueFactory(new PropertyValueFactory<>("protocol"));
        colLength.setCellValueFactory(new PropertyValueFactory<>("length"));
        colInfo.setCellValueFactory(new PropertyValueFactory<>("info"));

        packetList.setItems(filteredData);
//        packetList.setItems(packetData);
//////////////////////////////////////////////////////////////// do zmiany
        filterTextBox.setPromptText("filter");
        filterTextBox.setOnAction(event -> {
            String newValue = filterTextBox.getText();

            filteredData.setPredicate(packet -> {
                if (newValue == null || newValue.trim().isEmpty()) {
                    return true;
                }

                String[] conditions = newValue.split("&&");

                for (String condition : conditions) {
                    condition = condition.trim().toLowerCase();
                    if (condition.isEmpty()) continue;

                    if (condition.contains("==")) {
                        String[] parts = condition.split("==", 2);
                        String key = parts[0].trim();
                        String val = parts[1].trim();

                        boolean conditionMet = false;

                        switch (key) {
                            case "srcip":
                                conditionMet = packet.getSource() != null && packet.getSource().toLowerCase().equals(val);
                                break;
                            case "dstip":
                                conditionMet = packet.getDestination() != null && packet.getDestination().toLowerCase().equals(val);
                                break;
                            case "protocol":
                                conditionMet = packet.getProtocol() != null && packet.getProtocol().toLowerCase().contains(val);
                                break;
                            case "info":
                                conditionMet = packet.getInfo() != null && packet.getInfo().toLowerCase().contains(val);
                                break;
                            case "srcmac":
                                conditionMet = packet.getSourceMAC() != null && packet.getSourceMAC().toLowerCase().equals(val);
                                break;
                            case "dstmac":
                                conditionMet = packet.getDestinationMAC() != null && packet.getDestinationMAC().toLowerCase().equals(val);
                                break;
                            case "anomaly":
                                conditionMet = packet.isAnomaly();
                                break;
                            default:
                                return false;
                        }

                        if (!conditionMet) {
                            return false;
                        }

                    }
                }
                return true;
            });
        });
///////////////////////////////////////////////////////////////////////////////////////////////

        packetList.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                updateDetailsArea(newSelection);
            }
        });

        button1.setOnAction(event -> handleBackAction());

        if (fileQuit != null) {
            fileQuit.setOnAction(event -> System.exit(0));
        }
        protocolTree.setShowRoot(false);
        if(hexDump != null) {
            hexDump.setFont(Font.font("Consolas",12));
            hexDump.setEditable(false);
        }
    }

    private void startCaptureThread() {
        Thread captureThread = new Thread(() -> {
            program.listeningLoop(this::addPacketToTable);
        });

        captureThread.setDaemon(true);
        captureThread.start();
    }

    private void addPacketToTable(PacketLookupRow row) {
        Platform.runLater(() -> {
            packetData.add(row);

        });
    }

    private void updateDetailsArea(PacketLookupRow row) {
        if (row == null) {
            return;
        }

        MyPacket packet = null;

        // UWAGA: Zakładam, że masz metodę getPcapFilePath() w klasie Solution,
        // która zwraca ścieżkę do aktualnie zapisanego pliku zrzutu.
        String pcapPath = program.getPcapFilePath();

        try (analizasieci.packetCapture.PacketFileReader reader = new analizasieci.packetCapture.PacketFileReader(pcapPath)) {
            // Wczytanie z dysku pełnego, ciężkiego obiektu MyPacket na żądanie
            packet = reader.readPacket(row.getFileOffset());
        } catch (Exception e) {
            System.out.println("Błąd podczas odczytu pakietu z pliku pcap: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        if (packet == null){
            System.out.println("Pakiet NULL");
            return;
        }

        // 1. AKTUALIZACJA DRZEWA WARSTW (TreeView)
        TreeItem<String> rootItem = new TreeItem<>("Packet");

        for (ProtocolLayer layer : packet.getLayers()) {
            TreeItem<String> layerNode = new TreeItem<>(layer.getProtocolName());
            layerNode.setExpanded(true);

            for (Map.Entry<String, String> entry : layer.getFields().entrySet()) {
                TreeItem<String> fieldNode = new TreeItem<>(entry.getKey() + ": " + entry.getValue());
                layerNode.getChildren().add(fieldNode);
            }

            rootItem.getChildren().add(layerNode);
        }

        protocolTree.setRoot(rootItem);

        // 2. AKTUALIZACJA ZRZUTU SZESNASTKOWEGO (Hex Dump)
        if (hexDump != null) {
            hexDump.setText(packet.getHexDump());
        }
    }

    private void handleBackAction() {
        program.stopListening();

        try {
            WindowManager manager = new WindowManager();
            manager.showDevSelectWindow(program);

            Stage stage = (Stage) button1.getScene().getWindow();
            stage.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}